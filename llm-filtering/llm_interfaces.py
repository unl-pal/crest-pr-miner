import copy
from enum import Enum
from google import genai as gemini # type: ignore
from google.genai import types as gemini_types # type: ignore
import json
import ollama # type: ignore
import openai
import os
from pydantic import BaseModel, Field, create_model
from typing import Any, Type, Optional


def get_model(llm: str, use_cheapest: bool) -> str:
    if llm == "openai":
        return "gpt-6-luna" if use_cheapest else "gpt-6.1-terra"
    elif llm == "gemini":
        return "gemini-3.1-flash-lite" if use_cheapest else "gemini-3.8-flash"
    elif llm == "ollama":
        raise ValueError(f"For Ollama, you must specify the model via the --model argument")
    else:
        raise ValueError(f"Unknown LLM: {llm}")


def inline_schema(schema: dict) -> dict:
    """Recursively inline all $ref references from $defs."""
    defs = schema.get("$defs", {})
    
    def resolve(node):
        if isinstance(node, dict):
            # Inline references
            if "$ref" in node:
                ref_path = node["$ref"]
                if ref_path.startswith("#/$defs/"):
                    key = ref_path.split("/")[-1]
                    target = defs.get(key)
                    if target is None:
                        raise KeyError(f"Missing schema for ref {ref_path}")
                    # Deep copy to avoid mutation
                    return resolve(copy.deepcopy(target))
                else:
                    # Unknown ref type — leave it alone
                    return node
            # Otherwise, traverse children
            return {k: resolve(v) for k, v in node.items()}
        elif isinstance(node, list):
            return [resolve(v) for v in node]
        else:
            return node

    inlined = resolve(schema)
    inlined.pop("$defs", None)
    return inlined


def json_schema_to_base_model(schema: dict[str, Any], thinking: bool=False) -> Type[BaseModel]:
    type_mapping: dict[str, type] = {
        "string": str,
        "integer": int,
        "number": float,
        "boolean": bool,
        "array": list,
        "object": dict,
    }

    schema = schema.get("schema", {})
    properties = schema.get("properties", {})
    required_fields = schema.get("required", [])
    model_fields = {}

    def process_field(field_name: str, field_props: dict[str, Any]) -> tuple:
        """Recursively processes a field and returns its type and Field instance."""
        json_type = field_props.get("type", "string")
        enum_values = field_props.get("enum")

        # Handle Enums
        if enum_values:
            enum_name: str = f"{field_name.capitalize()}Enum"
            field_type = Enum(enum_name, {v: v for v in enum_values})
        # Handle Nested Objects
        elif json_type == "object" and "properties" in field_props:
            field_type = json_schema_to_base_model(
                field_props,
                thinking
            )  # Recursively create submodel
        # Handle Arrays with Nested Objects
        elif json_type == "array" and "items" in field_props:
            item_props = field_props["items"]
            if item_props.get("type") == "object":
                item_type: type[BaseModel] = json_schema_to_base_model(item_props, thinking)
            else:
                item_type: type = type_mapping.get(item_props.get("type"), Any)
            field_type = list[item_type]
        else:
            field_type = type_mapping.get(json_type, Any)

        # Handle default values and optionality
        default_value = field_props.get("default", ...)
        nullable = field_props.get("nullable", False)
        description = field_props.get("title", "")

        if nullable:
            field_type = Optional[field_type]

        if field_name not in required_fields:
            default_value = field_props.get("default", None)

        return field_type, Field(default_value, description=description)

    # Process each field
    for field_name, field_props in properties.items():
        model_fields[field_name] = process_field(field_name, field_props)
    if thinking:
        model_fields['thinking'] = str, Field(..., description='')

    return create_model(schema.get("title", "DynamicModel"), **model_fields)


def run_openai(prompt: str, model_name: str, thinking: bool=False, **kwargs: Any) -> str:
    openai.api_key = os.environ.get("OPENAI_API_KEY")
    client: openai.OpenAI = openai.OpenAI()

    args = {
        'reasoning': {"effort": "none"},
        'temperature': 0.2,
        'max_output_tokens': 2 * 1024,
        **kwargs,
    }
    if 'format' in args:
        if len(args['format']):
            args['text'] = {
                "format": {
                    "type": "json_schema",
                    "name": args["format"]["name"],
                    "strict": args["format"]["strict"],
                    "schema": args["format"]["schema"],
                }
            }
        del args['format']

    # Split prompt into system instructions and user data
    # The template ends with "# 6. PR Data" - everything before is system prompt
    # everything after (starting with "## PR Metadata") is user data
    splitPoint = "# **6. PR Data**"
    if splitPoint in prompt:
        system_prompt, user_data = prompt.split(splitPoint, 1)
        system_prompt = system_prompt.strip()
        user_data = splitPoint + user_data
    else:
        # Fallback if the split marker isn't found
        system_prompt = prompt
        user_data = ""

    response = client.responses.create(
        model=model_name,
        instructions=system_prompt,
        input=user_data,
        prompt_cache_key="pr-filtering-system-prompt",
		**args,
    )

    return response.output_text


# needed because Gemini does not allow "name"/"title" in JSON schemas
def replace_value(v):
    if isinstance(v, list):
        return [replace_value(i) for i in v]
    elif isinstance(v, dict):
        return replace_title_with_name(v)
    else:
        return v

def replace_title_with_name(obj: dict[str, Any]) -> dict[str, Any]:
    new_obj = {}
    for k, v in obj.items():
        if k != "title":
            new_obj[k] = replace_value(v)
    return new_obj


def run_gemini(user_input: str, model_name: str, thinking: bool=False, **kwargs: Any) -> str:
    generation_config = {
        "temperature": 0.2,
        "max_output_tokens": 16 * 1024,
        "response_mime_type": "text/plain",
    }
    for key, value in kwargs.items():
        if key == 'format':
            if len(value):
                schema = json_schema_to_base_model(value, thinking).model_json_schema()
                schema = replace_title_with_name(inline_schema(schema))
                generation_config['response_mime_type'] = 'application/json'
                generation_config['response_schema'] = schema
        else:
            generation_config[key] = value

    client = gemini.Client(api_key=os.environ.get("GEMINI_API_KEY"))
    response = client.models.generate_content(
        model=model_name,
        contents=str(user_input),
        config=gemini_types.GenerateContentConfig(**generation_config),
    )

    result = response.parsed if 'response_schema' in generation_config else response.text
    if 'response_schema' in generation_config:
        if 'thinking' in result:
            del result['thinking']
        result = json.dumps(result)
    return result


def run_ollama(prompt: str, model_name: str, thinking: bool=False, **kwargs: Any) -> str:
    schema = ''
    if 'format' in kwargs:
        if len(kwargs['format']):
            schema = json_schema_to_base_model(kwargs.get('format') or {}, thinking).model_json_schema()
        del kwargs['format']

    response: ollama.ChatResponse = ollama.chat(
        model=model_name,
        messages=[
            {
                'role': 'user',
                'content': str(prompt),
            },
        ],
        options={
            'temperature': 0.2,
            **kwargs,
        },
        format=schema,
    )
    result = response.message.content or ""
    if thinking and schema:
        result = json.loads(result)
        del result['thinking']
        result = json.dumps(result)
    return result
