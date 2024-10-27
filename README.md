# rickon

## Overview

The **Automated Recon Tool** is a powerful Flask application designed for automated reconnaissance in the background. It performs various tasks such as subdomain discovery, alive domain checks, tag analysis, and screenshot capture, while neatly presenting all gathered information. The tool also supports JavaScript analysis to identify sensitive API keys and endpoints through an advanced search feature. Additionally, it runs Nuclei and FFUF on the go, allowing users to view results based on their requirements.

## Features

- **Subdomain Discovery**: Automatically finds subdomains of a given domain.
- **Domain Status Check**: Checks if discovered domains are alive and responsive.
- **Tag Analysis**: Analyzes HTML tags for security vulnerabilities and insights.
- **Screenshot Capture**: Takes and stores screenshots of active domains for visual reference.
- **JavaScript Analysis**: Scans JavaScript files for sensitive information, such as API keys and endpoints.
- **Search Functionality**: Search through JavaScript dumps for specific terms and view snippets.
- **Nuclei Integration**: Runs Nuclei for vulnerability scanning on demand and displays results.
- **FFUF Integration**: Executes FFUF for fuzzing tasks and shows results as per user specifications.
- **Multi-Project Support**: Add and manage multiple projects for organized reconnaissance.

## Technologies Used

- **Backend**: Flask
- **Database**: PostgreSQL
- **Frontend**: Bootstrap (or any preferred UI framework)


```
docker-compose up
```


 - replace redis, postgres hosts in necessary files
 
 
 pass env
 psql_host
 psql_user
 psql_password
 redis_host
 redis_password

#video 1
https://github.com/user-attachments/assets/4c9e98e9-45f4-457e-bab2-ab7b31ea6507

#video 2

https://github.com/user-attachments/assets/aa2a5a18-d626-49ec-8502-d09e3e43cb2f

