import argparse
import csv
import sys
from pe_parser.unpacker import Unpacker
from pe_parser.headers_feature_extractor import HeadersFeatureExtractor
from pe_parser.import_feature_extractor import ImportFeatureExtractor
from pe_parser.section_feature_extractor import SectionFeatureExtractor
from pe_parser.string_feature_extractor import StringFeatureExtractor
from pe_parser.orchestrator import process_destination

def print_features(label: str, features: dict):
    print(f"\n{label}:\n")
    for key, value in features.items():
        print(f"  {key}: {value}")

def analyse_single(filepath: str, args):
    with Unpacker(filepath) as unpacker:
        run_all = args.all_flags
        if run_all or args.headers:
            print_features("Header features", HeadersFeatureExtractor(unpacker).extract_features())
        if run_all or args.sections:
            print_features("Section features", SectionFeatureExtractor(unpacker).extract_analysis_features())
        if run_all or args.imports:
            print_features("Import features", ImportFeatureExtractor(unpacker).export_import_features())
        if run_all or args.strings:
            print_features("String features", StringFeatureExtractor(unpacker).extract_string_features())

def analyse_batch(dirpath: str, args):
    results = process_destination(dirpath, args.recursive)
    if not results:
        print("No valid PE files found.", file=sys.stderr)
        return

    output_path = args.output or "features.csv"
    fieldnames = list(results[0].keys())

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"Processed {len(results)} files → {output_path}")

def main():
    parser = argparse.ArgumentParser(description="PE file analyser")

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", metavar="PATH", help="Single PE file to analyse")
    source.add_argument("--dir", metavar="PATH", help="Directory of PE files for batch extraction")

    # Single file display flags
    parser.add_argument("--headers", action=argparse.BooleanOptionalAction)
    parser.add_argument("--sections", action=argparse.BooleanOptionalAction)
    parser.add_argument("--imports", action=argparse.BooleanOptionalAction)
    parser.add_argument("--strings", action=argparse.BooleanOptionalAction)
    parser.add_argument("--all", dest="all_flags", action=argparse.BooleanOptionalAction,
                        help="Run all extractors (single file mode)")

    # Batch flags
    parser.add_argument("--recursive", "-r", action="store_true",
                        help="Recurse into subdirectories (batch mode)")
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="CSV output path (batch mode, default: features.csv)")

    args = parser.parse_args()

    if args.file:
        if not any([args.headers, args.sections, args.imports, args.strings, args.all_flags]):
            parser.error("Specify at least one flag: --headers --sections --imports --strings --all")
        analyse_single(args.file, args)

    elif args.dir:
        analyse_batch(args.dir, args)

if __name__ == '__main__':
    main()