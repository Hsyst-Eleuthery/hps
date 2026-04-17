package core

import "path/filepath"

func (s *Server) LogPath() string {
	return filepath.Join(s.FilesDir, "server.log")
}
