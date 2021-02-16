# lite


go get -d github.com/remmerw/lite

cd $GOPATH/src/github.com/remmerw/lite

go mod vendor

go mod tidy

cd $HOME

set GO111MODULE=off

gomobile bind -o lite-1.1.1.aar -v -androidapi=26 -target=android -ldflags="-s -w" github.com/remmerw/lite

