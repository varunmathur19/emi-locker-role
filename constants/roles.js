export const ROLES = {
  ADMIN: 1,
  CNF: 2,
  SUPER_DISTRIBUTOR: 3,
  DISTRIBUTOR: 4,
  FOS: 5,
  RETAILER: 6,
  EMPLOYEE: 7,
  STAFF: 8
};

// Role Validation
export const isValidRole = (role_id) => {
  return Object.values(ROLES).includes(Number(role_id));
};

export const BOOLEAN = {
  FALSE: 0,
  TRUE: 1
};