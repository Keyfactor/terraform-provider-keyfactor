#!/usr/bin/env bash
TAG_VERSION=v2.1.0-pre
git tag -d $TAG_VERSION || true
git push origin :$TAG_VERSION || true
git tag $TAG_VERSION
git push origin $TAG_VERSION