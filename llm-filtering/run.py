#!/usr/bin/env python
# coding: utf-8

import argparse
import datetime
from dotenv import load_dotenv
from llm_interfaces import get_model, run_gemini, run_ollama, run_openai
from prompt import build_prompt
import json
import os
from pathlib import Path
import re
import time
from tqdm import tqdm
import signal
from typing import Any, Dict, List, Optional


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run language models with command-line arguments.')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--output',
                        type=str,
                        help='Output directory to save the responses')
    group.add_argument('--showprompt',
                        action='store_true',
                        help='Show the generated prompt(s), but do not submit it')

    parser.add_argument('--directory',
                        type=str,
                        default=Path(__file__).resolve().parent.parent / 'data',
                        help='Data directory to search for PR files')
    parser.add_argument('--llm',
                        type=str,
                        choices=['openai', 'gpt5', 'gpt5full', 'gemini', 'geminipro', 'ollama'],
                        required=True,
                        help='LLM to use')
    parser.add_argument('--model',
                        type=str,
                        default=None,
                        help='Specific LLM model to use')
    parser.add_argument('--usecheapest',
                        action='store_true',
                        help='Should use the cheapest model')
    parser.add_argument('--thinking',
                        action='store_true',
                        help='If a thinking/reasoning model')
    parser.add_argument('--sleep',
                        type=int,
                        default=0,
                        help='Sleep time (milliseconds) between requests')
    parser.add_argument('--timeout',
                        type=int,
                        default=60 * 30,
                        help='Time out a request after this many seconds')
    parser.add_argument('--force',
                        action='store_true',
                        help='Force re-running, even if output already exists')
    parser.add_argument('--pr',
                        type=str,
                        help='Specific PR to process (given as "user/project/num")')
    parser.add_argument('--sample-only',
                        action='store_true',
                        help='Only process PRs in the sample')
    return parser.parse_args()


def find_files(directory: str) -> List[str]:
    found_files: List[str] = []
    for root, dirs, _ in os.walk(directory):
        for user in dirs:
            for _, dirs2, _ in os.walk(os.path.join(root, user)):
                for project in dirs2:
                    for _, dirs3, _ in os.walk(os.path.join(root, user, project)):
                        for pr in dirs3:
                            if re.match('[0-9]+', pr):
                                found_files.append(os.path.join(user, project, pr))
    found_files.sort()
    return found_files


def get_output_path(output_dir: str, input_path: str, llm: str, model_name: str) -> str:
    output_dir = os.path.join(output_dir, llm)
    output_dir = os.path.join(output_dir, model_name)
    os.makedirs(output_dir, exist_ok=True)

    output_filename: str = '_'.join(input_path.split('/')) + '_response.json'

    return os.path.join(output_dir, output_filename)


def add_metadata(response: str, llm: str, model_name: str, model_params: Dict[str, Any], input_path: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "date": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
        "PR": input_path,
        "llm": llm.strip(),
        "model_name": model_name.strip(),
        "model_params": model_params,
    }
    data["response"] = response.strip()
    return data


def save_response(output_path: str, output_data: Dict[str, Any]) -> None:
    with open(output_path, 'w') as file:
        json.dump(output_data, file, indent=2)
    print(f"Response saved to {output_path}")


# exponential backoff, in seconds
backoff: int = 60


class TimeoutException(Exception):
    pass


def signal_handler(signum: int, frame: Optional[Any]) -> None:
    raise TimeoutException()


def process_input_file(file_path: str, args: argparse.Namespace) -> None:
    global backoff

    prompt: str = build_prompt(file_path, args.directory)
    if args.showprompt:
        print(prompt)
        return

    model_name: str = ""
    if args.model:
        model_name = args.model
    else:
        try:
            model_name = get_model(args.llm, args.usecheapest)
        except ValueError:
            print(f"Error: Unknown model {args.llm}")
            return

    output_path: str = get_output_path(args.output, file_path, args.llm, model_name)
    if os.path.exists(output_path):
        if not args.force:
            print(f"Output file {output_path} already exists. Skipping.")
            return
        else:
            print(f"Output file {output_path} already exists. Overwriting.")
            os.remove(output_path)

    try:
        response: str = ""
        model_params: Dict[str, Any] = {}
        schema: Dict[str, Any] = {}
        schema_file: str = 'filter-schema.json'
        if os.path.exists(schema_file):
            with open(schema_file, 'r') as file:
                schema = json.load(file)

        if args.llm == 'openai':
            model_params['reasoning_effort'] = 'medium'
            model_params['max_completion_tokens'] = 16 * 1024
            response = run_openai(prompt, model_name, args.thinking, format=schema, **model_params)
        elif args.llm == 'gemini':
            model_params['temperature'] = 0.2
            model_params['max_output_tokens'] = 16 * 1024
            response = run_gemini(prompt, model_name, args.thinking, format=schema, **model_params)
        elif args.llm == 'ollama':
            model_params['temperature'] = 0.2
            response = run_ollama(prompt, model_name, args.thinking, format=schema, **model_params)
        else:
            raise ValueError(f"Unknown LLM: {args.llm}")

        data = add_metadata(response, args.llm, model_name, model_params, file_path)
        save_response(output_path, data)

        time.sleep(args.sleep / 1000.0)
    except TimeoutException as e:
        raise e
    except Exception as e:
        print(f"Error running LLM: {str(e)}")
        print(f"Continuing in {backoff} seconds")
        backoff *= 2
        time.sleep(backoff)


if __name__ == "__main__":
    args: argparse.Namespace = parse_arguments()

    load_dotenv()

    input_files = find_files(args.directory)
    if args.pr:
        if args.pr not in input_files:
            raise Exception(f"could not find PR '{args.pr}'")
        input_files = [args.pr]

    if args.sample_only:
        import csv
        sample_files = []
        with open('../sample-judgments-human.csv', 'r') as f:
            reader = csv.reader(f)
            next(reader)
            for row in reader:
                sample_files.append(row[0])
        input_files = [f for f in input_files if f in sample_files]

    for file_path in tqdm(input_files, desc="Processing PRs"):
        finished: bool = False
        while not finished:
            if hasattr(signal, "SIGALRM"):
                signal.signal(signal.SIGALRM, signal_handler)
                signal.alarm(args.timeout)

            try:
                process_input_file(file_path, args)
                finished = True
            except TimeoutException:
                print(f"Timeout processing {file_path}. Retrying...")
            finally:
                if hasattr(signal, "SIGALRM"):
                    signal.alarm(0)
