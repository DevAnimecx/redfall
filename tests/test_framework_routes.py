"""Framework breadth: Fastify and koa-router registrations are real routes, and
NestJS decorators are lifted to full route symbols.

Each fixture is ingested through the real pipeline; the assertions are the
extracted routes, nothing else was invented.
"""

from __future__ import annotations

from pathlib import Path

from redfall.ingestion.ingest import ingest

FASTIFY = """\
const fastify = require('fastify')();
const cache = require('./cache');

fastify.get('/users/:id', getUser);
fastify.post('/users', createUser);
cache.get('/users/:id', getUser);
"""

KOA = """\
import Router from 'koa-router';
const router = new Router();

router.post('/upload', uploadHandler);
router.get('/files/:name', fileHandler);
"""

NEST = """\
import { Controller, Get, Post, Param } from '@nestjs/common';

@Controller('cats')
export class CatsController {
  @Get()
  findAll(): string {
    return 'all';
  }

  @Post('create')
  create(@Param('id') id: string) {
    return id;
  }

  @Get(':id')
  findOne(@Param('id') id: string): string {
    return 'one';
  }
}
"""


def _write(tmp_path: Path, rel: str, source: str) -> None:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _routes(tmp_path, rel: str, source: str):
    _write(tmp_path, rel, source)
    result = ingest("test-framework", tmp_path)
    assert result.parse_errors == []
    return [(r.method, r.path, r.receiver, r.handler, r.line) for _, r in result.routes]


def test_fastify_registration_is_a_route_and_other_receivers_are_not(tmp_path):
    routes = _routes(tmp_path, "app.ts", FASTIFY)
    assert [(m, p) for m, p, _recv, _h, _ln in routes] == [
        ("GET", "/users/:id"),
        ("POST", "/users"),
    ]
    assert all(recv == "fastify" for _m, _p, recv, _h, _ln in routes)
    # `cache.get(...)` mirrors the shape but is not a route registration.
    assert len(routes) == 2


def test_koa_router_registration_is_a_route(tmp_path):
    routes = _routes(tmp_path, "routes.ts", KOA)
    assert [(m, p, h) for m, p, _recv, h, _ln in routes] == [
        ("POST", "/upload", "uploadHandler"),
        ("GET", "/files/:name", "fileHandler"),
    ]
    assert all(recv == "router" for _m, _p, recv, _h, _ln in routes)


def test_nestjs_decorators_become_full_routes(tmp_path):
    _write(tmp_path, "cats.controller.ts", NEST)
    result = ingest("test-framework", tmp_path)
    assert result.parse_errors == []
    routes = [(r.method, r.path, r.receiver, r.handler, r.line) for _, r in result.routes]
    assert [(m, p, h) for m, p, _recv, h, _ln in routes] == [
        ("GET", "/cats", "findAll"),
        ("POST", "/cats/create", "create"),
        ("GET", "/cats/:id", "findOne"),
    ]
    assert all(recv == "nest" for _m, _p, recv, _h, _ln in routes)
    # The route's span covers the method body, so taints inside a decorated
    # method are owned by the route the decorator declares.
    span = next(r for _, r in result.routes if r.receiver == "nest" and r.path == "/cats/:id")
    assert span.line <= 16 <= span.end_line, "findOne's @Get(':id') span must cover its body"
    assert span.end_line >= 18
