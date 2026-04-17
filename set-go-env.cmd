SET GO_VERSION=1.25.3

set GOVERSION=go%GO_VERSION%
set GOROOT=C:/usr/local/go/go-%GO_VERSION%-win64
set GOMOD=go.mod

set GO111MODULE=on
set GOARCH=amd64
set GOBIN=
set GOCACHE=C:\Users\%username%\AppData\Local\go-build
set GOENV=C:\Users\%username%\AppData\Roaming\go\env
set GOEXE=.exe
set GOEXPERIMENT=
set GOFLAGS=
set GOHOSTARCH=amd64
set GOHOSTOS=windows
set GOINSECURE=
set GOMODCACHE=C:\Users\%username%\go\pkg\mod
set GONOPROXY=
set GONOSUMDB=
set GOOS=windows
set GOPATH=C:\Users\%username%\go
set GOPRIVATE=
REM set GOPROXY=https://proxy.golang.org,direct
set GOPROXY=http://artifacts.smit.sise/artifactory/api/go/go,direct

set GOSUMDB=sum.golang.org
set GOTMPDIR=
set GOTOOLCHAIN=auto
set GOTOOLDIR=%GOROOT%\pkg\tool\windows_amd64
set GOVCS=

set GCCGO=gccgo
set GOAMD64=v1
set AR=ar
set CC=gcc
set CXX=g++
set CGO_ENABLED=1
set GOWORK=
set CGO_CFLAGS=-O2 -g
set CGO_CPPFLAGS=
set CGO_CXXFLAGS=-O2 -g
set CGO_FFLAGS=-O2 -g
set CGO_LDFLAGS=-O2 -g
set PKG_CONFIG=pkg-config
set GOGCCFLAGS=-m64 -fno-caret-diagnostics -Qunused-arguments -Wl,--no-gc-sections -fmessage-length=0 -ffile-prefix-map=C:\Users\%username%\AppData\Local\Temp\go-build=/tmp/go-build -gno-record-gcc-switches

SET GO_HOME=%GOROOT%
SET PATH=%GO_HOME%\bin;%PATH%

REM go mod tidy