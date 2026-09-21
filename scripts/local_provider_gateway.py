"""Run the distinct loopback gateway; this never admits a provider profile."""

import argparse

from securecode_ai.adapters.local_provider_gateway import GatewayPolicy, create_gateway_server


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--model-manifest-sha256", required=True)
    parser.add_argument("--port", type=int, default=11435)
    parser.add_argument("--backend-port", type=int, default=11434)
    parser.add_argument("--backend-version", default="0.16.2")
    args = parser.parse_args()
    policy = GatewayPolicy(
        args.model,
        args.model_manifest_sha256,
        backend_port=args.backend_port,
        backend_version=args.backend_version,
    )
    server = create_gateway_server(policy, port=args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
