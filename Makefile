BRANCH=`git rev-parse --abbrev-ref HEAD`
COMMIT=`git rev-parse --short HEAD`
GOLDFLAGS="-X main.branch $(BRANCH) -X main.commit $(COMMIT)"

PROGRAM=rserver

all:
	@go build -v -o $(PROGRAM)

test:
	@go test -v ./util/

tar:
	@rm -f app.gz.tar rserver
	@tar -vzcf app.gz.tar *

.PHONY: tar
