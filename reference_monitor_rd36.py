TYPE = "type"
ARGS = "args"
RETURN = "return"
EXCP = "exceptions"
TARGET = "target"
FUNC = "func"
OBJC = "objc"


class ABFile():
    def __init__(self, filename, create):

    # globals
    mycontext['debug'] = False
    # local (per object) reference to the underlying file
    self.Afn = filename + '.a'  ## create valid backup file
    self.Bfn = filename + '.b'  ## create empty write-to file
    # make the files and add 'SE' to the readat file...
    if create:  ## this case we need to create a new file
        self.Afile = openfile(self.Afn, create)
    self.Bfile = openfile(self.Bfn, create)
    self.Afile.writeat('SE', 0)  ## empty file, but contains S and E
    else:
    self.Afile = openfile(self.Afn, True)
    f = openfile(filename, create)
    self.Afile.writeat('SE', 0)
    self.Afile.writeat(f.readat(None, 0), 1)  ## copy everything in filename to


filename.a
self.Bfile = openfile(self.Bfn, True)
f.close()


def writeat(self, data, offset):


# Write the requested data to the B file using the sandbox's writeat call
self.Bfile.writeat(data, offset)  ## write to the .b file


def readat(self, bytes, offset):


# Read from the A file using the sandbox's readat...
return self.Afile.readat(bytes, offset)  ## read from the .a file


def close(self):
    if self.Bfile.readat(1, 0) + self.Bfile.readat(None, 0)[-1] == 'SE':  ## valid


inputs
self.Afile.writeat(self.Bfile.readat(None, 0), 0)
self.Afile.close()
self.Bfile.close()
removefile(self.Bfn)
else:  ## not valid inputs
self.Afile.close()
self.Bfile.close()
removefile(self.Bfn)


def ABopenfile(filename, create):


    return ABFile(filename, create)
# The code here sets up type checking and variable hiding for you.
# You should not need to change anything below here.
sec_file_def = {"obj-type": ABFile,
                "name": "ABFile",
                "writeat": {"type": "func", "args": (str,
                                                     (int, long)), "exceptions": Exception, "return":
                                (int, type(None)), "target": ABFile.writeat},
                "readat": {"type": "func", "args": ((int, long, type(None)),
                                                    (int, long)), "exceptions": Exception, "return": str,
                           "target": ABFile.readat},
                "close": {"type": "func", "args": None, "exceptions": None, "return":
                    (bool, type(None)), "target": ABFile.close}
                }
CHILD_CONTEXT_DEF["ABopenfile"] = {TYPE: OBJC, ARGS:
    (str, bool), EXCP: Exception, RETURN: sec_file_def, TARGET: ABopenfile}
CHILD_CONTEXT_DEF["openfile"] = {TYPE: OBJC, ARGS:
    (str, bool), EXCP: Exception, RETURN: sec_file_def, TARGET: ABopenfile}
# Execute the user code
secure_dispatch_module()
