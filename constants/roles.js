export const ROLES = {
  MASTER_ADMIN: 0,
  ADMIN: 1,
  CNF: 2,
  SUPER_DISTRIBUTOR: 3,
  DISTRIBUTOR: 4,
  FOS: 5,
  RETAILER: 6,
  SUB_RETAILER: 7,
  EMPLOYEE: 8,
  STAFF: 9,
};

export const isValidRole = (role_id) => {
  return Object.values(ROLES).includes(Number(role_id));
};

export const BOOLEAN = {
  FALSE: 0,
  TRUE: 1,
};