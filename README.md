# Serve current folder with SFTP

```bash
# for macOS
curl -L https://github.com/yene/sftpserver/releases/download/0.1.0/sftpserver-macos --output sftpserver
chmod +x ./sftpserver
./sftpserver
# connect to port 2222, with any user, and the given password
```

## Notes and TODOS
- [x] mDNS advertise
- [x] Print IP Address and Hostname
- [ ] listen for ctrl-c and shutdown clean

## Inspiration
* https://github.com/pkg/sftp/blob/v1.13.0/examples/go-sftp-server/main.go
