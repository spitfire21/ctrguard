# Why make this project
For much of my career, there has been skepticism involving how software is managed for developers that use docker containers. This project is to provide another tool to organizations to provide controls for their developers. There are many ways to control what images an organization can run, private registries, OPA and others, this can be used in addition to other tooling. 

My goal is to create a tool that security teams trust, allowing them to empower software engineering teams to use containers and container technologies to improve software development lifecycles.

I am also building this project as a way to learn. The FAPolicy tool is a utility that I want to use as a model for how software is approved to run at a machine level. 

# Feature
- [ ] Stop Docker from running unscanned / unapproved images
- [ ] Custom Image Policies
- [ ] Custom component policies
- [ ] Agent / server based polling of policies and scans

## Scans
I am currently modeling the policies to ride off of scans provided by Anchore/Grype. In the future, I want to support open formats that allow any scanners.


## Why Not Use OPA
Open Policy Agent is a great tool for security engineers to create refined rules for their systems. You see this often being used in K8s nodes to restrict what images can be used and with what features. What separates this tool from something like OPA is that this tool is a narrow focus on comparing image scans with policies to allow or deny a container to run. I would like to look into using open policy agent and the DSL they use to manage policies if I grow this project.