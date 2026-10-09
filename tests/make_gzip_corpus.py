#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/interfaces.pcapng.gz, the corpus's gzip-compressed capture.

It is tests/corpus/interfaces.pcapng (self-made by make_pcapng_corpus.py),
compressed in two gzip members, as `cat a.gz b.gz` joins them, so that the
corpus test reads a multi-member stream.  It converts to interfaces.txt,
the text of the capture in it.  The members carry no name and time 0, so
the file is the same on every run.

Run it from anywhere; it rewrites the file.
"""

import gzip
import pathlib

corpus = pathlib.Path(__file__).resolve().parent / "corpus"
capture = (corpus / "interfaces.pcapng").read_bytes()
half = len(capture) // 2
members = [gzip.compress(part, compresslevel=9, mtime=0) for part in (capture[:half], capture[half:])]
(corpus / "interfaces.pcapng.gz").write_bytes(b"".join(members))
