export GOOS=linux
go build && mv GoReSym GoReSym_lin
export GOOS=windows
go build && mv GoReSym.exe GoReSym_win.exe
export GOOS=darwin
go build && mv GoReSym GoReSym_mac
export GOOS=linux
