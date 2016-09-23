class PubSub(object):
    def __init__(self):
        self.handlers = {}

    def addHandler(self, name, handler):
        if not name in self.handlers:
            self.handlers[name] = []
        self.handlers[name].append(handler)

    def removeHandler(self, name, handler):
        if name in self.handlers and handler in self.handlers[name]:
            self.handlers[name].remove(handler)

    def emit(self, name, obj):
        if name in self.handlers:
            for handler in self.handlers[name]:
                handler(obj)

