.PHONY: build clean re

NAME = stockholm

build:
	go mod tidy
	go build

clean:
	@rm -fr $(NAME)

re: clean build
