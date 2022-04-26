#!/bin/sh

INITPWD=$(pwd)

if [ ! -f go/bin/go ]; then
	cd go/src && ./make.bash
	cd "$INITPWD"
fi


if [ ! -f bin/go-server-test ]; then
	"$INITPWD"/go/bin/go build "$INITPWD"/go-server-test/main.go
	mv main "$INITPWD/bin/go-server-test"
fi

if [ ! -f bin/vulnclient.jar ]; then
	cd "$INITPWD/vulnclient"
	mvn package
	cp target/vulnclient.jar "$INITPWD/bin/"
fi
