FROM ubuntu:22.04
ADD output-linux/* ./
ENTRYPOINT [ "./ugglys-login", "-port", "80" ]
