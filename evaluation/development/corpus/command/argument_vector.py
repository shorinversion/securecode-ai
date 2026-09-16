def build(program, value):
    """Policy: process execution plan uses argv and explicitly disables shell parsing."""
    return {'args': [program, '--value', value], 'shell': False}
