# template-render, a command-line utility for rendering templates
# Copyright (C) 2013 Mark Lee Stillwell 
#
# This program is free software: you can redistribute it and/or modify it under 
# the terms of the GNU General Public License as published by the Free Software 
# Foundation, either version 3 of the License, or any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT 
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS 
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

config_file_name = "~/.config/template-render/global_defaults.yaml"

def render_mako(data, meta):
    from mako.template import Template
    from mako.lookup import TemplateLookup

    if meta['block']:
        data = '<%block name="' + meta['block'] + '">' + data + '</%block>'

    if meta['template']:
        data = '<%inherit file="' + meta['template'] + '" />' + data

    lookup = TemplateLookup(meta['template_dirs'])

    template = Template(data, lookup=lookup, 
                        input_encoding=meta['input_encoding'], 
                        output_encoding=meta['output_encoding'])

    return template.render(meta=meta)

def render_jinja2(data, meta):
    from jinja2 import Environment, FileSystemLoader

    if meta['block']:
        data = '{% block ' + meta['block'] + ' %}' + data + '{% endblock %}'

    if meta['template']:
        data = '{% extends "' + meta['template'] + '" %}' + data

    loader = FileSystemLoader(meta['template_dirs'], 
                              encoding=meta['input_encoding'])

    env = Environment(loader=loader)

    template = env.from_string(data)

    return template.render(meta=meta).encode(meta['output_encoding'])

def main(argv=None):
    from argparse import ArgumentParser
    from os.path import isfile
    from sys import stdin, stdout
    from yaml import load as yload

    try:
        from yaml import CLoader as YLoader
    except ImportError:
        from yaml import Loader as YLoader

    engines = { 'mako' : render_mako, 'jinja2' : render_jinja2 }
    
    parser = ArgumentParser(description="Render a file using templates.")
    parser.add_argument('-i', '--inputfile', help='input file')
    parser.add_argument('-e', '--engine', help='templating engine')
    parser.add_argument('-d', '--template_dirs',
                        help=': delimited template search path')
    parser.add_argument('-t', '--template', 
                        help='template to apply to input file')
    parser.add_argument('-b', '--block', help='template block to override')
    parser.add_argument('-m', '--metafile', action='append',
                        help='metadata file in yaml format')
    parser.add_argument('-v', '--var', action='append', default=[],
                        help='name=value pairs to be added to metadata')
    parser.add_argument('-o', '--outputfile', default='-', help='output file')
    parser.add_argument('-ienc', '--input_encoding', help='input encoding')
    parser.add_argument('-oenc', '--output_encoding', help='output encoding')

    args = parser.parse_args()

    meta = dict()

    # defaults...
    meta['inputfile'] = None
    meta['engine'] = 'mako'
    meta['template'] = None
    meta['block'] = None
    meta['template_dirs'] = ['.']
    meta['input_encoding'] = 'utf-8'
    meta['output_encoding'] = 'utf-8'
    meta['output_format'] = 'html5'
    meta['outputfile'] = '-'

    metafiles = []
    
    if isfile(config_file_name):
        metafiles.append(config_file_name)

    if args.metafile:
        metafiles += args.metafile

    if metafiles:
        for metafile in args.metafile:
            if isfile(metafile):
                meta.update(yload(open(metafile, 'r'), Loader=YLoader))
            else:
                raise SystemExit("error: can't find metafile %s" % metafile)

    if args.var:
        for pair in args.var:
            name, value = pair.split('=')
            meta[name] = value

    if args.inputfile:
        meta['inputfile'] = args.inputfile

    if args.engine:
        meta['engine'] = args.engine
    
    if args.template:
        meta['template'] = args.template
 
    if args.block:
        meta['block'] = args.block
    
    if args.template_dirs:
        meta['template_dirs'] = args.template_dirs.split(':')
    
    if args.input_encoding:
        meta['input_encoding'] = args.input_encoding
 
    if args.output_encoding:
        meta['output_encoding'] = args.output_encoding

    if args.outputfile:
        meta['outputfile'] = args.outputfile
    
    fp = None
    if meta['inputfile']:
        if meta['inputfile'] == '-':
            fp = stdin
        elif isfile(meta['inputfile']):
            fp = open(meta['inputfile'], 'r')
        else:
            raise SystemExit("error: can't find %s" % args.inputfile)

    data = ""
    if fp:
        data = fp.read()

    if meta['outputfile'] == '-':
        out = stdout
    else:
        out = open(args.outputfile, 'w')

    out.write(engines[meta['engine']](data, meta))

if __name__ == "__main__":
    main()
