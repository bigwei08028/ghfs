package main

import (
	"archive/zip"
	"context"
	"crypto/md5"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/* favicon.png
var embeddedWeb embed.FS

// Config describes runtime options loaded from config.json (if present).
type Config struct {
	Listen      string   `json:"listen"`      // e.g. ":8901"
	Root        string   `json:"root"`        // base storage path
	TempDir     string   `json:"tempDir"`     // temp path for chunks
	EnableAuth  bool     `json:"enableAuth"`  // toggle basic auth
	Users       []User   `json:"users"`       // allowed users
	MaxUpload   int64    `json:"maxUploadMB"` // max single upload (MB)
	CORSOrigins []string `json:"corsOrigins"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Home     string `json:"home"` // subdirectory under root; empty means root
	IsAdmin  bool   `json:"isAdmin"`
	ReadOnly bool   `json:"readOnly"`
}

type appContext struct {
	cfg        Config
	userMap    map[string]User
	rootAbs    string
	tempAbs    string
	logger     *log.Logger
	accessFile *os.File
	mu         sync.Mutex
}

func main() {
	cfg := loadConfig()
	rootAbs, err := filepath.Abs(cfg.Root)
	if err != nil {
		log.Fatalf("resolve root: %v", err)
	}
	if err := os.MkdirAll(rootAbs, 0755); err != nil {
		log.Fatalf("create root: %v", err)
	}

	temp := cfg.TempDir
	if temp == "" {
		temp = filepath.Join(rootAbs, ".tmp")
	}
	tempAbs, err := filepath.Abs(temp)
	if err != nil {
		log.Fatalf("resolve temp: %v", err)
	}
	if err := os.MkdirAll(tempAbs, 0755); err != nil {
		log.Fatalf("create temp: %v", err)
	}

	accessLogPath := filepath.Join(tempAbs, "access.log")
	accessFile, err := os.OpenFile(accessLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("open access log: %v", err)
	}
	logger := log.New(accessFile, "", log.LstdFlags|log.Lshortfile)

	app := &appContext{
		cfg:        cfg,
		userMap:    toUserMap(cfg.Users),
		rootAbs:    rootAbs,
		tempAbs:    tempAbs,
		logger:     logger,
		accessFile: accessFile,
	}
	defer accessFile.Close()

	mux := http.NewServeMux()
	mux.Handle("/api/health", app.wrap(app.handleHealth))
	mux.Handle("/api/me", app.wrap(app.handleMe))
	mux.Handle("/api/list", app.wrap(app.handleList))
	mux.Handle("/api/download", app.wrap(app.handleDownload))
	mux.Handle("/api/download-zip", app.wrap(app.handleDownloadZip))
	mux.Handle("/api/upload", app.wrap(app.handleUpload))
	mux.Handle("/api/upload/chunk", app.wrap(app.handleUploadChunk))
	mux.Handle("/api/upload/complete", app.wrap(app.handleCompleteChunks))
	mux.Handle("/api/upload/zip", app.wrap(app.handleUploadZip))
	mux.Handle("/api/files", app.wrap(app.handleDelete))
	mux.Handle("/api/rename", app.wrap(app.handleRename))
	mux.Handle("/api/users", app.wrap(app.handleUsers))
	mux.Handle("/api/mkdir", app.wrap(app.handleMkdir))
	mux.Handle("/favicon.png", http.FileServer(http.FS(embeddedWeb)))
	webFS, err := fs.Sub(embeddedWeb, "web")
	if err != nil {
		log.Fatalf("embed web: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(webFS)))

	handler := withCORS(mux, cfg.CORSOrigins)
	//输出启动信息
	fmt.Printf("GHFS文件服务启动成功，请最小化本窗口，勿关闭本窗口！\n\n如需退出请按ctrl+c 或直接关闭本窗口。\n\n文件根目录位于：%s\n\n如需更换文件根目录，你可直接把ghfs.exe和config.json拷贝到目标目录后重新启动即可。\n\n端口%s，如需改更端口请修改config.json文件中的  \"listen\": \":8901\"。\n", rootAbs, cfg.Listen)

	// 输出
	fmt.Println("\n\n\n\n\n GHFS · Go Http File Server · 一个轻量级高性能的web文件服务器 · 内网文件共享专家 \n\n\n\n\n")

	if err := http.ListenAndServe(cfg.Listen, handler); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// loadConfig reads config.json; when absent it writes a default one for portable use.
func loadConfig() Config {
	defaultCfg := Config{
		Listen:      ":8901",
		Root:        "./data",
		TempDir:     "./tmp",
		EnableAuth:  true,
		MaxUpload:   512, // MB
		CORSOrigins: []string{"*"},
		Users: []User{
			{Username: "admin", Password: "admin", Home: ""},
		},
	}

	if _, err := os.Stat("config.json"); errors.Is(err, os.ErrNotExist) {
		if b, mErr := json.MarshalIndent(defaultCfg, "", "  "); mErr == nil {
			_ = os.WriteFile("config.json", b, 0644)
		}
		return defaultCfg
	}

	f, err := os.Open("config.json")
	if err != nil {
		return defaultCfg
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&defaultCfg); err != nil {
		log.Printf("warn: parse config.json failed, using defaults: %v", err)
	}
	return defaultCfg
}

// audit writes structured action logs to access.log.
func (a *appContext) audit(user *User, action string, kv ...string) {
	var b strings.Builder
	b.WriteString(action)
	b.WriteString(" user=")
	b.WriteString(username(user))
	for i := 0; i+1 < len(kv); i += 2 {
		b.WriteString(" ")
		b.WriteString(kv[i])
		b.WriteString("=")
		b.WriteString(kv[i+1])
	}
	a.logger.Println(b.String())
}

func toUserMap(users []User) map[string]User {
	m := make(map[string]User, len(users))
	for _, u := range users {
		// normalize password to md5 hex
		if len(u.Password) != 32 || strings.Contains(u.Password, ":") {
			h := md5.Sum([]byte(u.Password))
			u.Password = hex.EncodeToString(h[:])
		}
		if u.Username == "admin" {
			u.IsAdmin = true
			u.ReadOnly = false
		}
		m[u.Username] = u
	}
	return m
}

// wrap injects authentication, logging, and panic recovery.
func (a *appContext) wrap(fn func(http.ResponseWriter, *http.Request, *User) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		var user *User
		if a.cfg.EnableAuth {
			u, ok := a.basicAuth(r)
			if !ok {
				a.audit(nil, "AUTH_FAIL", "ip", r.RemoteAddr, "path", r.URL.Path)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			user = u
		}
		defer func() {
			if rec := recover(); rec != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				a.logger.Printf("panic: %v", rec)
			}
			a.logger.Printf("%s %s %s %dms user=%s",
				r.Method, r.URL.Path, r.URL.RawQuery, time.Since(start).Milliseconds(), username(user))
		}()

		if err := fn(w, r, user); err != nil {
			a.writeErr(w, err)
			a.logger.Printf("ERROR %s %s user=%s err=%v", r.Method, r.URL.Path, username(user), err)
		}
	})
}

func username(u *User) string {
	if u == nil {
		return "-"
	}
	return u.Username
}

func (a *appContext) basicAuth(r *http.Request) (*User, bool) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return nil, false
	}
	u, exists := a.userMap[username]
	if !exists {
		return nil, false
	}
	h := md5.Sum([]byte(password))
	if u.Password != hex.EncodeToString(h[:]) {
		return nil, false
	}
	return &u, true
}

func (a *appContext) writeErr(w http.ResponseWriter, err error) {
	var apiErr *httpError
	if errors.As(err, &apiErr) {
		http.Error(w, apiErr.Message, apiErr.Code)
		return
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

// httpError wraps an error with an HTTP status.
type httpError struct {
	Code    int
	Message string
}

func (e *httpError) Error() string { return e.Message }

func badRequest(msg string) *httpError { return &httpError{Code: http.StatusBadRequest, Message: msg} }
func forbidden(msg string) *httpError  { return &httpError{Code: http.StatusForbidden, Message: msg} }
func notFound(msg string) *httpError   { return &httpError{Code: http.StatusNotFound, Message: msg} }
func tooLarge(msg string) *httpError {
	return &httpError{Code: http.StatusRequestEntityTooLarge, Message: msg}
}

// resolvePath ensures a relative path stays within the user's home.
func (a *appContext) resolvePath(rel string, user *User) (string, error) {
	rel = filepath.Clean("/" + rel) // force leading slash then clean
	if rel == "/" {
		rel = ""
	} else {
		rel = strings.TrimPrefix(rel, "/")
	}
	userHome := a.rootAbs
	if user != nil && user.Home != "" {
		userHome = filepath.Join(a.rootAbs, user.Home)
	}
	target := filepath.Join(userHome, rel)
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(targetAbs, userHome) {
		return "", forbidden("path escapes root")
	}
	return targetAbs, nil
}

// --- Handlers --------------------------------------------------------------

func (a *appContext) handleHealth(w http.ResponseWriter, _ *http.Request, _ *User) error {
	return json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleMe returns current user info.
func (a *appContext) handleMe(w http.ResponseWriter, _ *http.Request, user *User) error {
	if user == nil {
		return badRequest("unauthorized")
	}
	return json.NewEncoder(w).Encode(map[string]interface{}{
		"username": user.Username,
		"isAdmin":  user.IsAdmin,
		"readOnly": user.ReadOnly,
		"home":     user.Home,
	})
}

// adminOnly enforces admin role.
func (a *appContext) adminOnly(user *User) error {
	if user == nil || !user.IsAdmin {
		return forbidden("admin only")
	}
	return nil
}

// saveUsers writes current users back to config.json.
func (a *appContext) saveUsers() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg := a.cfg
	// rebuild users slice from map to keep updates
	cfg.Users = make([]User, 0, len(a.userMap))
	for _, u := range a.userMap {
		cfg.Users = append(cfg.Users, u)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("config.json", data, 0644)
}

func (a *appContext) handleList(w http.ResponseWriter, r *http.Request, user *User) error {
	rel := r.URL.Query().Get("path")
	target, err := a.resolvePath(rel, user)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		if os.IsNotExist(err) {
			// auto-create empty directory for ease of browsing
			if mkErr := os.MkdirAll(target, 0755); mkErr != nil {
				return mkErr
			}
			entries = []os.DirEntry{}
		}
		if err != nil {
			return err
		}
	}
	type item struct {
		Name    string    `json:"name"`
		IsDir   bool      `json:"isDir"`
		Size    int64     `json:"size"`
		ModTime time.Time `json:"modTime"`
		Path    string    `json:"path"`
	}
	var list []item
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		info, _ := e.Info()
		entryPath := filepath.ToSlash(filepath.Join(rel, e.Name()))
		list = append(list, item{
			Name:    e.Name(),
			IsDir:   e.IsDir(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
			Path:    entryPath,
		})
	}
	a.audit(user, "LIST", "path", rel, "count", strconv.Itoa(len(list)))
	return json.NewEncoder(w).Encode(list)
}

// handleUsers manages users (admin only).
func (a *appContext) handleUsers(w http.ResponseWriter, r *http.Request, user *User) error {
	if err := a.adminOnly(user); err != nil {
		return err
	}
	switch r.Method {
	case http.MethodGet:
		type outUser struct {
			Username string `json:"username"`
			Home     string `json:"home"`
			IsAdmin  bool   `json:"isAdmin"`
			ReadOnly bool   `json:"readOnly"`
		}
		var list []outUser
		for _, u := range a.userMap {
			list = append(list, outUser{
				Username: u.Username,
				Home:     u.Home,
				IsAdmin:  u.IsAdmin,
				ReadOnly: u.ReadOnly,
			})
		}
		return json.NewEncoder(w).Encode(list)
	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Home     string `json:"home"`
			IsAdmin  bool   `json:"isAdmin"`
			ReadOnly bool   `json:"readOnly"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return badRequest("invalid body")
		}
		if req.Username == "" {
			return badRequest("username required")
		}
		if _, exists := a.userMap[req.Username]; exists {
			return badRequest("user exists")
		}
		if req.Password == "" {
			return badRequest("password required")
		}
		h := md5.Sum([]byte(req.Password))
		u := User{
			Username: req.Username,
			Password: hex.EncodeToString(h[:]),
			Home:     req.Home,
			IsAdmin:  req.IsAdmin,
			ReadOnly: req.ReadOnly,
		}
		a.userMap[u.Username] = u
		if err := a.saveUsers(); err != nil {
			return err
		}
		return json.NewEncoder(w).Encode(map[string]string{"status": "created"})
	case http.MethodPut:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"` // optional
			Home     string `json:"home"`
			IsAdmin  *bool  `json:"isAdmin"`
			ReadOnly *bool  `json:"readOnly"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return badRequest("invalid body")
		}
		u, ok := a.userMap[req.Username]
		if !ok {
			return notFound("user not found")
		}
		if req.Password != "" {
			h := md5.Sum([]byte(req.Password))
			u.Password = hex.EncodeToString(h[:])
		}
		u.Home = req.Home
		if req.IsAdmin != nil {
			u.IsAdmin = *req.IsAdmin
		}
		if req.ReadOnly != nil {
			u.ReadOnly = *req.ReadOnly
		}
		a.userMap[u.Username] = u
		if err := a.saveUsers(); err != nil {
			return err
		}
		return json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
	case http.MethodDelete:
		username := r.URL.Query().Get("username")
		if username == "" {
			return badRequest("username required")
		}
		if _, ok := a.userMap[username]; !ok {
			return notFound("user not found")
		}
		delete(a.userMap, username)
		if err := a.saveUsers(); err != nil {
			return err
		}
		return json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	default:
		return badRequest("unsupported method")
	}
}

func (a *appContext) handleDownload(w http.ResponseWriter, r *http.Request, user *User) error {
	rel := r.URL.Query().Get("path")
	if rel == "" {
		return badRequest("path required")
	}
	target, err := a.resolvePath(rel, user)
	if err != nil {
		return err
	}
	info, err := os.Stat(target)
	if err != nil {
		if os.IsNotExist(err) {
			return notFound("not found")
		}
		return err
	}
	if info.IsDir() {
		return badRequest("use /api/download-zip for folders")
	}
	a.audit(user, "DOWNLOAD", "path", rel, "bytes", strconv.FormatInt(info.Size(), 10))
	encoded := url.PathEscape(info.Name())
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"; filename*=UTF-8''%s", info.Name(), encoded))
	http.ServeFile(w, r, target)
	return nil
}

func (a *appContext) handleDownloadZip(w http.ResponseWriter, r *http.Request, user *User) error {
	rel := r.URL.Query().Get("path")
	target, err := a.resolvePath(rel, user)
	if err != nil {
		return err
	}
	info, err := os.Stat(target)
	if err != nil {
		if os.IsNotExist(err) {
			return notFound("not found")
		}
		return err
	}
	if !info.IsDir() {
		return badRequest("path must be directory")
	}
	zipName := info.Name() + ".zip"
	a.audit(user, "DOWNLOAD_ZIP", "path", rel)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", zipName))

	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	baseDir := target
	err = filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(baseDir, path)
		if err != nil {
			return err
		}
		f, err := zipWriter.Create(relPath)
		if err != nil {
			return err
		}
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(f, src)
		return err
	})
	if err != nil {
		return err
	}
	return nil
}

// handleUpload supports folder uploads (webkitRelativePath) and multiple files.
func (a *appContext) handleUpload(w http.ResponseWriter, r *http.Request, user *User) error {
	if user != nil && user.ReadOnly {
		return forbidden("read-only user")
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil { // 32MB memory
		return err
	}
	if a.cfg.MaxUpload > 0 && r.ContentLength > a.cfg.MaxUpload*1024*1024 {
		return tooLarge("payload exceeds limit")
	}
	files := r.MultipartForm.File["files"]
	paths := r.MultipartForm.Value["relpaths"] // legacy path carrier
	var manifest []string
	if m := r.FormValue("manifest"); m != "" {
		_ = json.Unmarshal([]byte(m), &manifest)
	}
	var wg sync.WaitGroup
	errCh := make(chan error, len(files))
	for i, fh := range files {
		wg.Add(1)
		go func(idx int, fh *multipart.FileHeader) {
			defer wg.Done()
			rel := fh.Filename
			if len(manifest) == len(files) {
				rel = manifest[idx]
			} else if len(paths) == len(files) {
				rel = paths[idx] // prefer explicit relative path if provided
			}
			dst, err := a.resolvePath(rel, user)
			if err != nil {
				errCh <- err
				return
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
				errCh <- err
				return
			}
			src, err := fh.Open()
			if err != nil {
				errCh <- err
				return
			}
			defer src.Close()
			out, err := os.Create(dst)
			if err != nil {
				errCh <- err
				return
			}
			defer out.Close()
			if _, err := io.Copy(out, src); err != nil {
				errCh <- err
				return
			}
			a.audit(user, "UPLOAD_FILE", "path", rel, "bytes", strconv.FormatInt(fh.Size, 10))
		}(i, fh)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		return err
	}
	a.audit(user, "UPLOAD", "count", strconv.Itoa(len(files)))
	return json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleUploadZip: receives a zip file field "zipfile", optional form field "dest".
// Extracts while preserving directory structure into dest (relative).
func (a *appContext) handleUploadZip(w http.ResponseWriter, r *http.Request, user *User) error {
	if user != nil && user.ReadOnly {
		return forbidden("read-only user")
	}
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		return err
	}
	file, header, err := r.FormFile("zipfile")
	if err != nil {
		return badRequest("zipfile required")
	}
	defer file.Close()

	if a.cfg.MaxUpload > 0 && header.Size > a.cfg.MaxUpload*1024*1024 {
		return tooLarge("zip exceeds limit")
	}

	destRel := r.FormValue("dest")
	destRoot, err := a.resolvePath(destRel, user)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(destRoot, 0755); err != nil {
		return err
	}

	// store to temp file to satisfy zip.NewReader requirement (needs ReaderAt+size)
	tempZipPath := filepath.Join(a.tempAbs, fmt.Sprintf("zip-%d.tmp", time.Now().UnixNano()))
	tempFile, err := os.Create(tempZipPath)
	if err != nil {
		return err
	}
	written, err := io.Copy(tempFile, file)
	tempFile.Close()
	if err != nil {
		os.Remove(tempZipPath)
		return err
	}

	zipFile, err := os.Open(tempZipPath)
	if err != nil {
		return err
	}
	defer func() {
		zipFile.Close()
		os.Remove(tempZipPath)
	}()

	stat, err := zipFile.Stat()
	if err != nil {
		return err
	}
	if a.cfg.MaxUpload > 0 && stat.Size() > a.cfg.MaxUpload*1024*1024 {
		return tooLarge("zip exceeds limit")
	}

	reader, err := zip.NewReader(zipFile, stat.Size())
	if err != nil {
		return badRequest("invalid zip")
	}

	var extracted int
	var totalBytes int64
	for _, f := range reader.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := filepath.Clean(f.Name)
		// prevent path traversal
		if strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			return badRequest("zip contains illegal path")
		}
		targetPath := filepath.Join(destRoot, name)
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(targetPath)
		if err != nil {
			rc.Close()
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			rc.Close()
			out.Close()
			return err
		}
		extracted++
		totalBytes += int64(f.UncompressedSize64)
		rc.Close()
		out.Close()
	}

	a.audit(user, "UPLOAD_ZIP", "files", strconv.Itoa(extracted), "bytes", strconv.FormatInt(totalBytes, 10), "dest", destRel)
	return json.NewEncoder(w).Encode(map[string]string{
		"status":   "unzipped",
		"files":    fmt.Sprint(len(reader.File)),
		"bytes_in": fmt.Sprint(written),
	})
}

// Chunk upload handler for large files.
// Form fields: uploadId, relPath, chunkIndex, totalChunks, chunk (file)
func (a *appContext) handleUploadChunk(w http.ResponseWriter, r *http.Request, user *User) error {
	if user != nil && user.ReadOnly {
		return forbidden("read-only user")
	}
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		return err
	}
	uploadID := r.FormValue("uploadId")
	relPath := r.FormValue("relPath")
	if relPath == "" {
		return badRequest("relPath required")
	}
	chunkIdxStr := r.FormValue("chunkIndex")
	totalStr := r.FormValue("totalChunks")
	file, _, err := r.FormFile("chunk")
	if err != nil {
		return badRequest("chunk file required")
	}
	defer file.Close()

	chunkIdx, err := strconv.Atoi(chunkIdxStr)
	if err != nil {
		return badRequest("invalid chunkIndex")
	}
	totalChunks, err := strconv.Atoi(totalStr)
	if err != nil {
		return badRequest("invalid totalChunks")
	}

	tempDir := filepath.Join(a.tempAbs, uploadID)
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return err
	}
	chunkPath := filepath.Join(tempDir, fmt.Sprintf("%06d.part", chunkIdx))

	// Skip existing chunk to support resume.
	if _, err := os.Stat(chunkPath); err == nil {
		return json.NewEncoder(w).Encode(map[string]string{"status": "exists"})
	}
	out, err := os.Create(chunkPath)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, file); err != nil {
		return err
	}
	pos, _ := out.Seek(0, io.SeekCurrent)
	a.logger.Printf("UPLOAD-CHUNK uploadId=%s idx=%d/%d path=%s size=%d user=%s", uploadID, chunkIdx, totalChunks, relPath, pos, username(user))
	return json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "stored",
		"chunkIndex":  chunkIdx,
		"totalChunks": totalChunks,
	})
}

// handleCompleteChunks merges stored parts into final file.
// JSON body: {uploadId, relPath, totalChunks}
func (a *appContext) handleCompleteChunks(w http.ResponseWriter, r *http.Request, user *User) error {
	if user != nil && user.ReadOnly {
		return forbidden("read-only user")
	}
	var req struct {
		UploadID    string `json:"uploadId"`
		RelPath     string `json:"relPath"`
		TotalChunks int    `json:"totalChunks"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return badRequest("invalid body")
	}
	if req.UploadID == "" || req.RelPath == "" || req.TotalChunks <= 0 {
		return badRequest("missing fields")
	}
	tempDir := filepath.Join(a.tempAbs, req.UploadID)
	if _, err := os.Stat(tempDir); err != nil {
		return badRequest("upload not found")
	}

	dst, err := a.resolvePath(req.RelPath, user)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	for i := 0; i < req.TotalChunks; i++ {
		partPath := filepath.Join(tempDir, fmt.Sprintf("%06d.part", i))
		part, err := os.Open(partPath)
		if err != nil {
			return badRequest(fmt.Sprintf("missing chunk %d", i))
		}
		if _, err := io.Copy(out, part); err != nil {
			part.Close()
			return err
		}
		part.Close()
	}
	// cleanup
	os.RemoveAll(tempDir)
	a.logger.Printf("MERGE uploadId=%s path=%s chunks=%d user=%s", req.UploadID, req.RelPath, req.TotalChunks, username(user))
	return json.NewEncoder(w).Encode(map[string]string{"status": "merged"})
}

func (a *appContext) handleDelete(w http.ResponseWriter, r *http.Request, user *User) error {
	if r.Method != http.MethodDelete {
		return badRequest("DELETE required")
	}
	if user != nil && user.ReadOnly {
		return forbidden("read-only user")
	}
	rel := r.URL.Query().Get("path")
	if rel == "" {
		return badRequest("path required")
	}
	target, err := a.resolvePath(rel, user)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(target); err != nil {
		return err
	}
	a.audit(user, "DELETE", "path", rel)
	return json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

func (a *appContext) handleRename(w http.ResponseWriter, r *http.Request, user *User) error {
	if r.Method != http.MethodPost {
		return badRequest("POST required")
	}
	if user != nil && user.ReadOnly {
		return forbidden("read-only user")
	}
	var req struct {
		Path    string `json:"path"`
		NewName string `json:"newName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return badRequest("invalid body")
	}
	if req.Path == "" || req.NewName == "" {
		return badRequest("path and newName required")
	}
	oldPath, err := a.resolvePath(req.Path, user)
	if err != nil {
		return err
	}
	newPath := filepath.Join(filepath.Dir(oldPath), req.NewName)
	if err := os.Rename(oldPath, newPath); err != nil {
		return err
	}
	a.audit(user, "RENAME", "from", req.Path, "to", req.NewName)
	return json.NewEncoder(w).Encode(map[string]string{"status": "renamed"})
}

func (a *appContext) handleMkdir(w http.ResponseWriter, r *http.Request, user *User) error {
	if r.Method != http.MethodPost {
		return badRequest("POST required")
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return badRequest("invalid body")
	}
	if req.Path == "" {
		return badRequest("path required")
	}
	target, err := a.resolvePath(req.Path, user)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	a.audit(user, "MKDIR", "path", req.Path)
	return json.NewEncoder(w).Encode(map[string]string{"status": "created"})
}

// --- helpers ----------------------------------------------------------------

// withCORS enables simple CORS for SPA frontends.
func withCORS(next http.Handler, origins []string) http.Handler {
	allow := strings.Join(origins, ",")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", allow)
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// contextKey avoids collisions in request context.
type contextKey string

func (a *appContext) withUser(r *http.Request, u *User) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), contextKey("user"), u))
}
