"""Loopback-only TLS transport for the synthetic account browser fixture."""

import argparse
import asyncio
import ssl


async def forward(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def handle(reader, writer, target_port):
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(
            "127.0.0.1", target_port
        )
    except OSError:
        writer.close()
        await writer.wait_closed()
        return
    await asyncio.gather(
        forward(reader, upstream_writer),
        forward(upstream_reader, writer),
        return_exceptions=True,
    )


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server = await asyncio.start_server(
        lambda reader, writer: handle(reader, writer, args.target_port),
        host="127.0.0.1", port=0, ssl=context
    )
    print(server.sockets[0].getsockname()[1], flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
