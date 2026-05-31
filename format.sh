#!/bin/zsh

if which swift-comment-reflow &>/dev/null; then
	swift-comment-reflow -cd Sources Tests
else
	echo "swift-comment-reflow not found, skipping"
fi
swiftformat Sources Tests
