package main

import "testing"

func TestSSHCopyEndpointsRequireOneManagedRemote(t *testing.T) {
	for _, tc := range []struct {
		source, destination, remote, local, path string
		upload                                   bool
	}{
		{"local.txt", "deploy@host.example.test:remote.txt", "deploy@host.example.test", "local.txt", "remote.txt", true},
		{"deploy@host.example.test:/tmp/remote file", "local file", "deploy@host.example.test", "local file", "/tmp/remote file", false},
		{"./local@name:part", "deploy@host.example.test:-filename", "deploy@host.example.test", "./local@name:part", "-filename", true},
	} {
		remote, options, err := sshCopyEndpoints(tc.source, tc.destination)
		if err != nil || remote != tc.remote || options.LocalPath != tc.local || options.RemotePath != tc.path || options.Upload != tc.upload {
			t.Fatalf("copy endpoints: %q %+v %v", remote, options, err)
		}
	}
	for _, endpoints := range [][2]string{
		{"local", "other"},
		{"deploy@one.example.test:a", "deploy@two.example.test:b"},
		{"local", "root@host.example.test:file"},
		{"local", "deploy@host.example.test:"},
		{"local", "deploy@host.example.test:file\nsecret"},
		{"local", "ssh://deploy@host.example.test/file"},
		{"local", "deploy@host.example.test;bad:file"},
	} {
		if _, _, err := sshCopyEndpoints(endpoints[0], endpoints[1]); err == nil {
			t.Fatalf("invalid transfer accepted: %q", endpoints)
		}
	}
}
