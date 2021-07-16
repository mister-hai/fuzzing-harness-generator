
class CodeQLMeta(object):
    def __init_(self):
        pass
    
    def codeqlquery(self,query):
        self.queryoutputfilename = lambda filename: '{}.bqrs'.format(filename)
        self.codeqlquery = 'codeql query run {} -o {} {} -d {}'.format( 
                query,
                self.queryoutputfilename,
                self.codeqloutputdir)

    def bqrsdecode(self):
        command = "codeql bqrs decode --format=csv {} onearg.bqrs -o {bqrsoutput} {outputcsvfile}"
        pass
