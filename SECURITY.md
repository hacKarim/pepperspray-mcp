# Security policy

## Read this first

This project drives offensive security tooling. Point it only at systems you
own or have written permission to test. Unauthorised scanning is a crime in
most jurisdictions, and nothing in this repository changes that.

The tooling is meant to run inside the Docker container, not on your host.
That containment is a safety property of the design, not a convenience.

## Reporting a vulnerability

Open a private security advisory through the Security tab rather than a public
issue. The findings that matter here:

- Command injection through an MCP tool argument. Every tool takes a target
  from the client and builds a command line from it, so this is the first
  place to look.
- Anything that escapes the container, or that reaches a host path the
  compose file did not mount.
- The TCP bridge accepting a connection it should not, or exposing the server
  beyond localhost by default.
- A tool that writes outside `results/`.

Include the exact MCP request. A proof of concept against your own instance is
better than a description.

## What is not a vulnerability

- The tools being capable of harm. That is what they are.
- A finding that needs an operator to pass a malicious target deliberately.

I will acknowledge within a week. This is a personal project with no paid
support behind it.

## Supported versions

The tip of `main`.
