(component
  (type $route
    (instance
      (export "handle" (type $handle (sub resource)))
      (type $borrow-handle (borrow $handle))
      (type $own-handle (own $handle))
      (type $inspect-type (func (param "value" $borrow-handle) (result u32)))
      (type $transfer-type (func (param "value" $own-handle)))
      (export "inspect" (func (type $inspect-type)))
      (export "transfer" (func (type $transfer-type)))))
  (import "test:c64-resource/route@1.0.0" (instance $route-in (type $route))))
