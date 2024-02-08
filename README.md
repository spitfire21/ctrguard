# Why make this project
For much of my career, there has been skepticism involving how software is managed for developers that use docker containers. This project is to provide another tool to organizations to provide controls for their developers. There are many ways to control what images an organization can run, private registries, OPA and others, this can be used in addition to other tooling. 

I am also building this project as a way to learn. The FAPolicy tool is a utility that I want to use as a model for how software is approved to run at a machine level. 

# Feature
- [ ] Stop Docker from running unscanned / unapproved images
- [ ] Custom Image Policies
- [ ] Custom component policies
- [ ] Agent / server based polling of policies and scans

## Scans
I am currently modeling the policies to ride off of scans provided by Anchore/Grype. In the future, I want to support open formats that allow any scanners.