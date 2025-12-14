import { Request, Response, NextFunction } from 'express';
import clientService from '../services/clientService';
import revokeService from '../services/revokeService';
import webhookService from '../services/webhookService';

async function listApplications(_req: Request, res: Response, next: NextFunction) {
  try {
    const apps = await clientService.listApplications();
    res.json(apps);
  } catch (err) {
    next(err);
  }
}

async function createApplication(req: Request, res: Response, next: NextFunction) {
  try {
    const app = await clientService.createApplication(req.body);
    res.status(201).json(app);
  } catch (err) {
    next(err);
  }
}

async function updateApplication(req: Request, res: Response, next: NextFunction) {
  try {
    const app = await clientService.updateApplication(req.params.id, req.body);
    res.json(app);
  } catch (err) {
    next(err);
  }
}

async function deleteApplication(req: Request, res: Response, next: NextFunction) {
  try {
    await clientService.deleteApplication(req.params.id);
    res.status(204).send();
  } catch (err) {
    next(err);
  }
}

async function listSubApplications(_req: Request, res: Response, next: NextFunction) {
  try {
    res.json(await clientService.listSubApplications());
  } catch (err) {
    next(err);
  }
}

async function createSubApplication(req: Request, res: Response, next: NextFunction) {
  try {
    res.status(201).json(await clientService.createSubApplication(req.body));
  } catch (err) {
    next(err);
  }
}

async function updateSubApplication(req: Request, res: Response, next: NextFunction) {
  try {
    res.json(await clientService.updateSubApplication(req.params.id, req.body));
  } catch (err) {
    next(err);
  }
}

async function deleteSubApplication(req: Request, res: Response, next: NextFunction) {
  try {
    await clientService.deleteSubApplication(req.params.id);
    res.status(204).send();
  } catch (err) {
    next(err);
  }
}

async function listClients(_req: Request, res: Response, next: NextFunction) {
  try {
    res.json(await clientService.listClients());
  } catch (err) {
    next(err);
  }
}

async function createClient(req: Request, res: Response, next: NextFunction) {
  try {
    res.status(201).json(await clientService.createClient(req.body));
  } catch (err) {
    next(err);
  }
}

async function updateClient(req: Request, res: Response, next: NextFunction) {
  try {
    res.json(await clientService.updateClient(req.params.id, req.body));
  } catch (err) {
    next(err);
  }
}

async function deleteClient(req: Request, res: Response, next: NextFunction) {
  try {
    await clientService.deleteClient(req.params.id);
    res.status(204).send();
  } catch (err) {
    next(err);
  }
}

async function listWebhooks(_req: Request, res: Response, next: NextFunction) {
  try {
    res.json(await webhookService.listWebhooks());
  } catch (err) {
    next(err);
  }
}

async function createWebhook(req: Request, res: Response, next: NextFunction) {
  try {
    res.status(201).json(await webhookService.createWebhook(req.body));
  } catch (err) {
    next(err);
  }
}

async function updateWebhook(req: Request, res: Response, next: NextFunction) {
  try {
    res.json(await webhookService.updateWebhook(req.params.id, req.body));
  } catch (err) {
    next(err);
  }
}

async function deleteWebhook(req: Request, res: Response, next: NextFunction) {
  try {
    await webhookService.deleteWebhook(req.params.id);
    res.status(204).send();
  } catch (err) {
    next(err);
  }
}

async function bulkRevoke(req: Request, res: Response, next: NextFunction) {
  try {
    const result = await revokeService.bulkRevoke(req.body);
    res.json(result);
  } catch (err) {
    next(err);
  }
}

async function bulkRevokeForSubApplication(req: Request, res: Response, next: NextFunction) {
  try {
    const result = await revokeService.bulkRevoke({ sub_application_id: req.params.id });
    res.json(result);
  } catch (err) {
    next(err);
  }
}

export default {
  listApplications,
  createApplication,
  updateApplication,
  deleteApplication,
  listSubApplications,
  createSubApplication,
  updateSubApplication,
  deleteSubApplication,
  listClients,
  createClient,
  updateClient,
  deleteClient,
  listWebhooks,
  createWebhook,
  updateWebhook,
  deleteWebhook,
  bulkRevoke,
  bulkRevokeForSubApplication
};
