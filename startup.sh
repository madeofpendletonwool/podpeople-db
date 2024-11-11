#!/bin/sh

# Create the data directory
mkdir -p /app/podpeople-data

# Create the database if it doesn't exist
touch /app/podpeople-data/podpeopledb.sqlite

# Start the main application
/root/main