import argparse
import asyncio
import ssl


async def forward(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def handle_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    target_port: int,
) -> None:
    try:
        target_reader, target_writer = await asyncio.open_connection(
            "127.0.0.1",
            target_port,
        )
    except OSError:
        client_writer.close()
        await client_writer.wait_closed()
        return

    await asyncio.gather(
        forward(client_reader, target_writer),
        forward(target_reader, client_writer),
        return_exceptions=True,
    )


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)

    server = await asyncio.start_server(
        lambda reader, writer: handle_client(reader, writer, args.target_port),
        host="0.0.0.0",
        port=args.listen_port,
        ssl=context,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
