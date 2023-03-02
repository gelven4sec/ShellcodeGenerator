# ShellcodeGenerator

## Usage

Generate the shellcode :
```sh
make
```

Paste the output inside de `code` variable in `test_shellcode.c`.

Compile the shellcode tester:
```sh
make build_test
```

Start a listener on another terminal :
```sh
nc -lvnp 8989
```

Then execute the tester :
```sh
./build/test_shellcode
```

Now you should see the connection on your listener !
