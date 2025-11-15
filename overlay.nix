# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025 zebreus
final: prev: {
  agenix = prev.callPackage ./pkgs/agenix.nix { };
}
