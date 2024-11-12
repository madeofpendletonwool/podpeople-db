# PodPeopleDB

PodPeopleDB is an open-source database for podcast hosts and guests, serving as the IMDB of podcasting. It automatically indexes podcast host information from podcast feeds and allows manual submissions of host/guest information.

## Features

- **Podcast Host Database**: Track hosts and guests across different podcasts
- **Automatic Feed Parsing**: Extracts host information from `<podcast:person>` tags in podcast feeds
- **Manual Submissions**: Allow users to submit additional host/guest information
- **Public API**: Access podcast host data programmatically
- **SQLite Database**: Download the entire database for offline use
- **Admin Dashboard**: Moderate and approve host submissions

## How It Works

PodPeopleDB uses the Podcast Index Feed ID to look up podcasts and automatically extracts host information from podcast feeds that use the podcasting 2.0 `<podcast:person>` tags. For podcasts without these tags, users can manually submit host information.

### Data Structure

- **Hosts**: Names, roles, descriptions, images, and associated podcasts
- **Podcasts**: Title, description, author, owner, images, and feed URLs
- **Automatic Updates**: Keeps host information current based on feed data

## API Endpoints

```
GET /api/podcast/{id}     - Get podcast information by Podcast Index ID
GET /api/hosts/{id}       - Get hosts for a specific podcast
GET /api/recent-hosts     - Get recently added hosts
GET /api/download-database - Download the entire SQLite database
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/podpeople-db.git
```

2. Build the Docker container:
```bash
docker build -t podpeople-db .
```

3. Run the container:
```bash
docker run -p 8080:8080 podpeople-db
```

### Environment Variables

- `ADMIN_USERNAME`: Admin dashboard username (default: admin)
- `ADMIN_PASSWORD`: Admin dashboard password (default: admin)
- `SEARCH_API_URL`: URL for the Podcast Index API

## Usage

1. Access the web interface at `http://localhost:8080`
2. Enter a Podcast Index Feed ID to look up a podcast
3. View host information or submit new host details
4. Download the database for offline use

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Technologies Used

- Go (1.23+)
- SQLite
- Gorilla Mux for routing
- HTMX for dynamic content
- Docker for containerization

## License

This project is open source and available under the [GNU GENERAL PUBLIC LICENSE](LICENSE).

## Acknowledgments

- Thanks to the Podcast Index for providing the podcast data API
- Built to support the Podcasting 2.0 initiative and namespace
- Inspired by the need for better podcast host discovery and tracking

## Security Note

Please make sure to change the default admin credentials in production by setting the appropriate environment variables.

## ToDo

- Additional Admin Users
- Add same user multiple pods
- Add Episode specific entries