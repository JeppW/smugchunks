import argparse
from core.executor import Executor

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', action="append", help="target URL")
    parser.add_argument('-i', '--input-file', help="path to file with list of target URLs")
    parser.add_argument('-m', '--method', default="POST", help="HTTP method to use (default: POST)")
    parser.add_argument('-H', '--header', action="append", help="extra header to include in requests")
    parser.add_argument('-t', '--timeout', default=7.0, type=float, help="timeout in seconds required to accept a finding (default: 7)")
    parser.add_argument('-o', '--output', help="path to output file")
    parser.add_argument('-l', '--limit', default=2, type=int, help="maximum number of findings per target before flagging as false positive (default: 2)")
    parser.add_argument('-q', '--quiet', action="store_true", help="suppress output")
    args = parser.parse_args()

    if not args.url and not args.input_file:
        print("You must specify either --url or --input-file.")
        exit()
    
    if args.url and args.input_file:
        print("You can only specify one of --url and --input-file, not both.")
        exit()
    
    if args.timeout <= 0:
        print("--timeout must be greater than zero.")
        exit()

    return args


if __name__ == "__main__":
    args = parse_args()

    try:
        urls = args.url or open(args.input_file, encoding="utf-8", errors="replace").readlines()
    except OSError as e:
        print(f"Invalid input file: {e.__class__.__name__}")
        exit()

    executor = Executor(method=args.method.upper(), urls=urls,
                            headers=args.header, findings_limit=args.limit,
                                output=args.output, timeout=args.timeout, quiet=args.quiet)
    
    try:
        executor.execute()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        exit()

