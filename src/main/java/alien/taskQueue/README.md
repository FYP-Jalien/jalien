# Introducing New Job Brokering Parameters

This document explain how to add or remove new parameters to Job Broker using Site Sonar Infrastructure constraints.

# Adding Parameters
Please follow the following order for introducing new matching parameters

- Ensure the required parameter is being reported by Site Sonar already. If not, create a new test in Site Sonar to report this parameter(The parameter of concern can be a part of an existing test in Site Sonar).
- Extract the parameter and add it to the Site Map by updating AliMonitor's [constraint definition page] (http://alimonitor.cern.ch/sitesonar/constraints.jsp). This will ensure that this parameter will be injected to the Site Map from the Job Agent.
- Create a new column in `JOBAGENT` table with the name of the new parameter(Ensure that the name defined in constraints page and the column name is the same) with the default value `Null`
- Enter the new parameter in `SITESONAR_CONSTRAINTS` table.
    - The parameter **name** should be equal to the column name introduced in the `JOBAGENT` table
    - The **expression** can be either `equality` or `regex`. **equality** will ensure that the value in JDL is compared with the value reported by the site for an exact match. **regex** will ensure that a MySQL `LIKE` match is done on the value in the JDL with the value reported by the site.

- Now the **same parameter name** can be used in the JDL to request the job to be run in a site with that specific value for that parameter
-
# Removing/Changing Parameters
If  it is required to temporarily disable the parameter, this can be done by setting `enabled` to `false` for the specific constraint in the `SITESONAR_CONSTRAINT` table.

If it is required to remove/change the parameter, ensure that you follow the reverse order of adding a parameter.
- Remove the relevant constraint row from the `SITESONAR_CONSTRAINTS` table.
- Remove the relevant column from the Job Agent table.
- Remove the parameter extraction logic from the constraint definition page.
- Remove the test from Site Sonar altogether if necessary.
