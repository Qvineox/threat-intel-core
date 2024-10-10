# GRPC compilation

```shell
cd proto
protoc --go_out=../services --go_opt=paths=source_relative --go-grpc_out=../services --go-grpc_opt=paths=source_relative *.proto 
```

## Additional materials

* https://habr.com/ru/articles/774796/
* https://www.geeksforgeeks.org/how-to-install-protocol-buffers-on-windows/
* https://github.com/grpc/grpc-go/blob/master/examples/features/metadata/server/main.go
* https://grpc.io/docs/guides/metadata/