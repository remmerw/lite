# lite


go get -d github.com/remmerw/lite

cd $GOPATH/src/github.com/remmerw/lite
go mod vendor
go mod tidy

cd $HOME
set GO111MODULE=off
gomobile bind -o lite-1.0.0.aar -v -androidapi=24 -target=android github.com/remmerw/lite