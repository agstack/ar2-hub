# Licensed under the EUPL, Version 1.2 or – as soon they will be approved by
# the European Commission - subsequent versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at:
# https://joinup.ec.europa.eu/software/page/eupl

"""hub_main refuses to import without these two variables. The shapefile is
only opened when a route resolves a country, and the registry list is only
read when a route proxies, so placeholders are enough for unit tests."""

import os

os.environ.setdefault("WORLD_SHP_FILE", "/nonexistent/world.shp")
os.environ.setdefault("REGISTRY_SERVERS", '[{"url": "http://127.0.0.1:8001", "countries": ["USA"]}]')
os.environ.setdefault("DATABASE_URL", "sqlite://")
