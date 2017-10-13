BRANCH=`git rev-parse --abbrev-ref HEAD`
COMMIT=`git rev-parse --short HEAD`
GOLDFLAGS="-X main.branch $(BRANCH) -X main.commit $(COMMIT)"

PROGRAM=rserver

all:
	@go build -v -o $(PROGRAM)

test:
	@go test -v ./util/
