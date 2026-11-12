# Azure notes

The full deployment guide is [AZURE_DEPLOY.md](AZURE_DEPLOY.md). This page is only the cost and isolation summary.

## What you pay for

- **Path A, App Service for Linux:** one small plan (Basic or Standard, one instance). Managed TLS and Entra sign-in are included. Do not use the Free tier for real use and do not autoscale.
- **Path B, one small VM:** about $8 a month for a Standard_B1s left running, plus disk and IP. Stop it when idle.
- **Storage account** (optional): Standard LRS, one private container named `evidence`. Cents per GB-month.
- Do not buy Front Door, Application Gateway, Document Intelligence or Azure OpenAI for this version.
- The AI questionnaire uses a model provider you choose, billed by that provider. `ENTROPY_AI=off` removes it. ServiceNow and Jira ticketing are optional and use your existing instances.

## Isolation

One instance, one data folder, one organisation. For a second organisation, deploy a second instance and a second storage account. Do not put two companies in one data folder or one container.
