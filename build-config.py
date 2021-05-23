#!/usr/bin/python3

from os import listdir
from io import StringIO
from sys import argv, exit, stderr, stdout
from os.path import isfile, isdir, islink, join, abspath, dirname


class Builder(object):
    def __init__(self):
        self.base = None
        self.dirs = dict()
        self.files = dict()

    def __str__(self):
        pass

    def build(self, dir):
        if not isdir(dir):
            raise ValueError(f'Path "{dir}" is not a directory!')
        self.base = abspath(dir)
        self._dir(self.base, True)

    def _file(self, path):
        if path.endswith(".md"):
            return
        b = path.replace(self.base, "")
        if len(b) == 0:
            raise ValueError(f'Invalid file path "{path}"!')
        if b.startswith(".git"):
            return
        if b[0] != "/":
            b = f"/{b}"
        d = dirname(b)
        if len(d) > 1:
            if d not in self.dirs:
                self.dirs[d] = 1
            else:
                self.dirs[d] += 1
        r = None
        with open(path, "r") as f:
            r = f.read()
        if not isinstance(r, str) or len(r) == 0:
            self.files[b] = f'/usr/bin/printf "" > "${{ROOT}}${{SYSCONFIG_DIR}}{b}"'
            return
        i = 0
        o = StringIO()
        e = [f'/usr/bin/printf "" > "${{ROOT}}${{SYSCONFIG_DIR}}{b}"']
        # need to index
        for c in r:
            if i >= 80:
                e.append(
                    f"/usr/bin/printf '{o.getvalue()}' >> \"${{ROOT}}${{SYSCONFIG_DIR}}{b}\""
                )
                o.truncate(0)
                o.seek(0)
                o.flush()
                i = 0
            if c == "\n":
                o.write("\\n")
                i += 1
            elif c == "\t":
                o.write("\\t")
                i += 1
            elif c == "\\":
                o.write("\\\\")
                i += 1
            elif c == "'":
                o.write("'\\''")
                i += 3
            elif c == "%":
                o.write("%%")
                i += 1
            else:
                o.write(c)
            i += 1
        if o.tell() > 0:
            e.append(
                f"/usr/bin/printf '{o.getvalue()}' >> \"${{ROOT}}${{SYSCONFIG_DIR}}{b}\""
            )
        del o
        self.files[b] = "\n".join(e)
        del e

    def write(self, output):
        output.write(
            f"#!/bin/bash\n# Automatically generated build files script.\n# Args: {' '.join(argv)}\n\n"
        )
        for k, v in self.dirs.items():
            if v == 0 or len(k) <= 1:
                continue
            if k[0] != "/":
                k = f"/{k}"
            output.write(f'mkdir -p "${{ROOT}}${{SYSCONFIG_DIR}}{k}" 2> /dev/null\n')
        output.write("\n")
        for k, v in self.files.items():
            output.write(f'# Create file "{k}"\n')
            output.write(v)
            output.write("\n\n")

    def print(self, file=None):
        if isinstance(file, str) and len(file) > 0:
            with open(file, "w") as o:
                self.write(o)
            return
        return self.write(stdout)

    def _dir(self, path, base=False):
        if isfile(path):
            return self._file(path)
        if not isdir(path):
            print(f'Ignoring non file/dir entry "{path}".', file=stderr)
            return
        for f in listdir(path):
            p = join(path, f)
            if base and (f == ".git" or f == "LICENSE" or f.lower().endswith(".md")):
                continue
            if (not isdir(p) and not isfile(p)) or islink(p):
                print(f'Ignoring non file/dir entry "{path}".', file=stderr)
                continue
            if isdir(p):
                self._dir(p, False)
                continue
            self._file(p)


if __name__ == "__main__":
    if len(argv) < 2:
        print(f"{argv[0]} <chroot> [outscript]", file=stderr)
        exit(1)

    file = None
    if len(argv) >= 3:
        file = argv[2]

    try:
        b = Builder()
        b.build(argv[1])
        b.print(file)
    except Exception as err:
        print(f"{err}", file=stderr)
        exit(1)
    exit(0)