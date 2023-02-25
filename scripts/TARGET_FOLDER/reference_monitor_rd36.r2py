"""
This security layer inadequately handles A/B storage for files in RepyV2.



Note:
    This security layer uses encasementlib.r2py, restrictions.default, repy.py and Python
    Also you need to give it an application to run.
    python repy.py restrictions.default encasementlib.r2py [security_layer].r2py [attack_program].r2py

    """
TYPE="type"
ARGS="args"
RETURN="return"
EXCP="exceptions"
TARGET="target"
FUNC="func"
OBJC="objc"

mycontext['lock'] = createlock()

class ABFile():
  def __init__(self,filename,create):
    # globals
    mycontext['debug'] = False
    # local (per object) reference to the underlying file
    self.Afn = filename+'.a'
    self.Bfn = filename+'.b'

    # make the files and add 'SE' to the readat file...
    mycontext['lock'].acquire(True)

    if create:

      if not self.Afn in listfiles():
        self.Afile = openfile(self.Afn, create)
        self.Bfile = openfile(self.Bfn, create)
        self.Afile.writeat('SE', 0)
      else:
        self.Afile = openfile(self.Afn, create)
        self.Bfile = openfile(self.Bfn, create)

    else:
      if not self.Afn in listfiles():
        self.Afile = openfile(self.Afn, create)
        self.Bfile = openfile(self.Bfn, create)
        self.Afile.writeat('SE', 0)
      else:
        self.Afile = openfile(self.Afn, create)
        self.Bfile = openfile(self.Bfn, create)


  def writeat(self,data,offset):

    if self.Bfn in listfiles():

      bstring = self.Bfile.readat(None, 0)

      if offset == 0:
        self.Bfile.writeat(data,offset)

      elif offset < 0:
        pass

      elif offset > len(bstring):
        pass

      elif offset <= len(bstring):
        self.Bfile.writeat(data,offset)

    else:
      pass

  def readat(self,bytes,offset):

    if self.Afn in listfiles():

      if offset < 0:
        pass

      elif offset > len(self.Afile.readat(None, 0)):
        pass

      else:
        # Read from the A file using the sandbox's readat...
        return self.Afile.readat(bytes,offset)

    else:
      pass

  def close(self):

    bstring = self.Bfile.readat(None, 0)

    self.Afile.close()
    self.Bfile.close()

    if bstring[0] == 'S' and bstring[-1] == 'E':
      removefile(self.Afn)
      self.Afile = openfile(self.Afn, True)
      self.Afile.writeat(bstring, 0)
      self.Afile.close()
    else:
      pass

    mycontext['lock'].release()



def ABopenfile(filename, create):
  return ABFile(filename,create)




# The code here sets up type checking and variable hiding for you.  You
# should not need to change anything below here.
sec_file_def = {"obj-type":ABFile,
                "name":"ABFile",
                "writeat":{"type":"func","args":(str,int),"exceptions":Exception,"return":(int,type(None)),"target":ABFile.writeat},
                "readat":{"type":"func","args":((int,type(None)),(int)),"exceptions":Exception,"return":str,"target":ABFile.readat},
                "close":{"type":"func","args":None,"exceptions":None,"return":(bool,type(None)),"target":ABFile.close}
           }

CHILD_CONTEXT_DEF["ABopenfile"] = {TYPE:OBJC,ARGS:(str,bool),EXCP:Exception,RETURN:sec_file_def,TARGET:ABopenfile}

# Execute the user code
secure_dispatch_module()