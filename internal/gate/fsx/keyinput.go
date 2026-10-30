//go:build linux

package fsx

import (
	"io"
	"os"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/template"
)

// CommandKeyInputs searches each file a command's matched template reads
// through a {path:read} or {path:read:fd} placeholder for a private-key
// header (handoff N-35, POLICY §4): the command could print a range of it,
// such as tail does, which the output redaction cannot recognise without
// the BEGIN line. args are the resolved arguments, fds the opened
// descriptors in template order. Only regular files are searched: a
// directory, and whatever a command opens by itself, are not (POLICY §3,
// the residual). Up to maxHashBytes a file is searched whole, as read_file
// searches it, a {path:read:fd} through its descriptor without moving its
// offset; a holder is refused with path_denied, naming the command, unless
// allowKeys (the command's reads_private_keys) is set. A larger file is not
// searched, and over reports it: the caller masks the command's output with
// redact.MaskKeyBodies instead.
func (f *FS) CommandKeyInputs(command string, tpl *template.Template, args []string, fds []template.Descriptor, allowKeys bool) (over bool, err error) {
	next := 0
	for i, tok := range tpl.Tokens {
		var found, large bool
		name := args[i]
		switch tok.Kind {
		case template.PathRead:
			found, large, err = f.pathHoldsKey(name)
		case template.PathReadFD:
			if next >= len(fds) {
				return false, errf(protocol.CodeInternal, "a file passed as a descriptor is missing; nothing was run")
			}
			name = fds[next].Path
			found, large, err = fileHoldsKey(fds[next].File)
			next++
		default:
			continue
		}
		if err != nil {
			return false, err
		}
		over = over || large
		if found && !allowKeys {
			return false, errf(protocol.CodePathDenied, "%q holds a private key, and command %s does not declare reads_private_keys "+
				"(a command could print a range of it without its BEGIN line, which output redaction needs; POLICY §4); nothing was run", name, command)
		}
	}
	return over, nil
}

// pathHoldsKey opens the resolved path p as ResolveRead does and searches
// it (fileHoldsKey).
func (f *FS) pathHoldsKey(p string) (found, large bool, err error) {
	l, err := f.locate(p, false)
	if err != nil {
		return false, false, err
	}
	defer l.close()
	file, err := f.openTarget(l)
	if err != nil {
		return false, false, err
	}
	defer func() { _ = file.Close() }()
	return fileHoldsKey(file)
}

// fileHoldsKey reports whether the regular file holds a private-key header
// anywhere, reading it through ReadAt (its offset is unchanged), and large
// when it is above maxHashBytes and not searched. Anything but a regular
// file holds none.
func fileHoldsKey(file *os.File) (found, large bool, err error) {
	fi, err := file.Stat()
	if err != nil {
		return false, false, mapErr(err)
	}
	if !fi.Mode().IsRegular() {
		return false, false, nil
	}
	if fi.Size() > maxHashBytes {
		return false, true, nil
	}
	k := &keyScan{}
	if _, err := io.Copy(k, io.NewSectionReader(file, 0, fi.Size())); err != nil {
		return false, false, mapErr(err)
	}
	return k.found, false, nil
}
