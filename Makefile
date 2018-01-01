
PROGRAM=rserver

$(PROGRAM):
	@go build -o $@

clean:
	$(RM) $(PROGRAM)

test:
	@go test ./util/

install:
	@go install

