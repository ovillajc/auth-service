export interface Profile {
  user: User;
  client: Client;
  roles: SharedColumns[];
  permissions: SharedColumns[];
  rigs: RigElement[];
  instances: Instance[];
}

export interface Client {
  company_name: string;
  created_at: Date;
  updated_at: Date;
  location: string;
  rfc: string;
  is_active: boolean;
  responsible_id: string;
  id: string;
}

export interface Instance {
  id: string;
  rig: RoleClass;
  roles: RoleClass[];
}

export interface RoleClass {
  id: string;
  name: string;
}

export interface SharedColumns {
  name: string;
  description: string;
  created_at: Date;
  id: string;
}

export interface RigElement {
  name: string;
  description: string;
  created_at: Date;
  updated_at: Date;
  allowed_users: number;
  id: string;
  client_id: string;
}

export interface User {
  id: string;
  name: string;
  email: string;
  position: string;
  phone: string;
  is_active: boolean;
  created_at: Date;
  updated_at: Date;
  client_id: string;
}
