def uppercase(value: str):
    return value.upper()


def dispatch(handler_name: str, payload: str):
    handler = globals()[handler_name]
    return handler(payload)
