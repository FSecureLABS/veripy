from abstract import Base
from cStringIO import StringIO
from libs import SGMLTemplate
from os import path
from scapy.all import wrpcap


class HTMLFormatter(Base):

    Assets = ['empty-file.png', 'jquery.min.js', 'log-file.png', 'logo-mini.png', 'pcap-file.png', 'veripy.css', 'veripy.js']
    TemplateDir = path.join(path.dirname(path.abspath(__file__)), 'html_data')

    def format(self, p):
        # prepare an input buffer, containing the content of the template
        f = open(path.join(HTMLFormatter.TemplateDir, 'template.html'))
        i = StringIO(f.read())
        f.close()
        # prepare an output buffer to write the generated XML to
        o = StringIO()

        sgml = SGMLTemplate({ 'report': self.report, 'asset_path': path.basename(p + '_files') }, ouf=o)
        # use the SGMLTemplate to generate the formatted report
        sgml.xcopy(i)

        o.reset()
        # write the contents of the output buffer to file, using ui.write_file()
        # to allow the output path to be dynamically changed
        self.write_file(p, o.read())
        # create a directory to write the various assets and linked files to
        self.create_directory(p + '_files')
        # copy any static assets into the output directory
        for asset in HTMLFormatter.Assets:
            self.copy_file(path.join(HTMLFormatter.TemplateDir, asset), path.join(p + '_files', asset))
        # write the logs and pcap data for each result to file
        for suite in self.report.results():
            for result in suite.results():
                self.create_directory(path.join(p + '_files', str(id(result))))

                # write the test case log file
                self.write_file(path.join(p + '_files', str(id(result)), "veripy.log"), result.outcome.log)
                # write the network pcap data into a log file
                for (link, pcap) in result.outcome.network_dumps:
                    if len(pcap) > 0:
                        wrpcap(path.join(p + '_files', str(id(result)), "link-%s.pcap" % link), pcap)

    def type(self):
        return "html"
